//! QEMU `savevm` completeness and exact-restore admission.
//!
//! Exact fat checkpoints are a production realization path. A restored runtime
//! is admitted only after the replay oracle proves that its continuation is
//! content-equal to the corresponding deterministic replay. Thin checkpoints
//! remain a distinct storage representation; they are not a fallback for an
//! incomplete VMState implementation.

use crucible::ContentHash;
use thiserror::Error;

/// Gate proving paired QEMU VMState and host-I/O exact restore.
pub const QEMU_SAVEVM_COMPLETENESS_CHECK: &str = "checks.crucible.phase2.qemuExactSnapshotRestore";

/// Default policy for using QEMU `savevm`/`loadvm` in Crucible.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QemuSavevmCompletenessPolicy;

impl QemuSavevmCompletenessPolicy {
    /// Returns the production policy for complete paired fat checkpoints.
    #[must_use]
    pub const fn complete() -> Self {
        Self
    }

    /// Attempts to accept a `loadvm`-realized runtime under this policy.
    ///
    /// # Errors
    ///
    /// Returns a replay-oracle validation error when the comparison was not run
    /// or the loaded and replayed continuations differ.
    pub fn accept_loadvm_realized_runtime(
        self,
        validation: QemuReplayOracleValidation,
    ) -> Result<QemuLoadvmRealizationAdmission, QemuSavevmPolicyError> {
        validate_loadvm_realized_runtime(validation)
    }

    /// Authorizes the low-level QMP `loadvm` command for snapshot-completeness probes.
    ///
    /// This authorization is only for the independent completeness probe that
    /// compares a loaded VMState suffix to deterministic replay. It is not a
    /// runtime-realization admission token.
    #[must_use]
    pub const fn authorize_loadvm_probe(self) -> QemuLoadvmCommandAuthorization {
        QemuLoadvmCommandAuthorization {
            purpose: QemuLoadvmCommandPurpose::SnapshotCompletenessProbe,
        }
    }

    /// Authorizes the low-level QMP `loadvm` command for exact runtime realization.
    #[must_use]
    pub const fn authorize_loadvm_runtime(self) -> QemuLoadvmCommandAuthorization {
        QemuLoadvmCommandAuthorization {
            purpose: QemuLoadvmCommandPurpose::RuntimeRealization,
        }
    }

    /// Authorizes QMP `loadvm` for the trusted baked-genesis ready-point snapshot.
    ///
    /// This authorization is deliberately separate from the exact fat-checkpoint
    /// runtime branch because it only loads a baked genesis snapshot produced by
    /// `bake`.
    #[must_use]
    pub const fn authorize_baked_genesis_runtime(self) -> QemuLoadvmCommandAuthorization {
        QemuLoadvmCommandAuthorization {
            purpose: QemuLoadvmCommandPurpose::BakedGenesisRealization,
        }
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
    fn complete_policy_authorizes_baked_genesis_and_exact_loadvm() {
        let policy = QemuSavevmCompletenessPolicy::complete();

        assert_eq!(
            policy.authorize_baked_genesis_runtime().purpose(),
            QemuLoadvmCommandPurpose::BakedGenesisRealization
        );
        assert_eq!(
            policy.authorize_loadvm_runtime().purpose(),
            QemuLoadvmCommandPurpose::RuntimeRealization
        );
    }

    fn content_hash_with_byte(byte: u8) -> ContentHash {
        ContentHash { bytes: [byte; 32] }
    }
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
