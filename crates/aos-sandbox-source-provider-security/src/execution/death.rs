//! Opaque same-boot and cross-boot provider death evidence.

use std::num::NonZeroU32;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::pidfd::PidFd;
use sha2::{Digest as _, Sha256};

use super::{CurrentKernelBootV1, ProcessExecutionEvidenceV1};
use crate::SourceProviderSecurityError;
use crate::carrier::ClosedSourceProviderCarrierV1;

/// Proves one exact provider execution cannot continue an unresolved session.
///
/// The proof alone grants no journal mutation or session-replacement authority.
/// Construction remains sealed behind current custody, an exact protected
/// AOSSPL snapshot, and kernel-observed process exit or identity replacement.
pub struct DeadProviderExecutionV1 {
    evidence: DeathEvidenceV1,
}

enum DeathEvidenceV1 {
    SameBoot {
        boot_id: [u8; 16],
        observed_at_seconds: i64,
        process_id: u32,
        start_time_ticks: u64,
        process_instance: [u8; 16],
        process_execution_digest: ObjectDigest,
    },
    CrossBoot {
        old_boot_id: [u8; 16],
        current_boot_id: [u8; 16],
        observed_at_seconds: i64,
        process_id: u32,
        start_time_ticks: u64,
        process_instance: [u8; 16],
        process_execution_digest: ObjectDigest,
    },
}

/// Identifies the kernel proof class behind durable execution-death evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderExecutionDeathKindV2 {
    /// A pidfd/identity observation proved exit or PID reuse on the same boot.
    PidfdExited,
    /// A fresh kernel boot identity differs from the retained execution boot.
    BootReplaced,
}

/// Projects move-only death evidence into canonical nonauthorizing facts.
pub struct DeadProviderExecutionProjectionV2 {
    kind: ProviderExecutionDeathKindV2,
    old_boot_id: [u8; 16],
    observed_boot_id: [u8; 16],
    observed_at_seconds: i64,
    process_id: u32,
    start_time_ticks: u64,
    process_instance: [u8; 16],
    process_execution_digest: ObjectDigest,
    commitment: ObjectDigest,
}

impl core::fmt::Debug for DeadProviderExecutionProjectionV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DeadProviderExecutionProjectionV2([authenticated death])")
    }
}

impl DeadProviderExecutionProjectionV2 {
    /// Returns the closed proof class.
    #[must_use]
    pub const fn kind(&self) -> ProviderExecutionDeathKindV2 {
        self.kind
    }

    /// Returns old boot, process ID, start time, and process-instance identity.
    #[must_use]
    pub const fn old_execution(&self) -> ([u8; 16], u32, u64, [u8; 16]) {
        (
            self.old_boot_id,
            self.process_id,
            self.start_time_ticks,
            self.process_instance,
        )
    }

    /// Returns the observed boot identity and observation time.
    #[must_use]
    pub const fn observation(&self) -> ([u8; 16], i64) {
        (self.observed_boot_id, self.observed_at_seconds)
    }

    /// Returns the canonical authenticated death commitment.
    #[must_use]
    pub const fn commitment(&self) -> ObjectDigest {
        self.commitment
    }

    /// Returns the exact AOSMSA02 full provider-execution digest.
    #[must_use]
    pub const fn process_execution_digest(&self) -> ObjectDigest {
        self.process_execution_digest
    }

    pub(crate) fn matches(
        &self,
        boot_id: [u8; 16],
        process_id: u32,
        start_time_ticks: u64,
        process_instance: [u8; 16],
    ) -> bool {
        self.old_execution() == (boot_id, process_id, start_time_ticks, process_instance)
            && self.commitment == death_projection_commitment(self)
    }
}

impl core::fmt::Debug for DeadProviderExecutionV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let _ = &self.evidence;
        formatter.write_str("DeadProviderExecutionV1([redacted])")
    }
}

pub(super) struct UnresolvedProviderSessionReceiptV1 {
    pub(super) process_instance: [u8; 16],
}

pub(super) struct RecoveredProviderExecutionV1 {
    pub(super) old_boot_id: [u8; 16],
    pub(super) process_id: u32,
    pub(super) start_time_ticks: u64,
    pub(super) process_instance: [u8; 16],
    pub(super) process_execution_digest: ObjectDigest,
}

impl DeadProviderExecutionV1 {
    /// Consumes liveness authority into durable, non-reusable projection facts.
    #[must_use]
    pub fn into_durable_projection(self) -> DeadProviderExecutionProjectionV2 {
        let (
            kind,
            old_boot_id,
            observed_boot_id,
            observed_at_seconds,
            process_id,
            start_time_ticks,
            process_instance,
            process_execution_digest,
        ) = match self.evidence {
            DeathEvidenceV1::SameBoot {
                boot_id,
                observed_at_seconds,
                process_id,
                start_time_ticks,
                process_instance,
                process_execution_digest,
            } => (
                ProviderExecutionDeathKindV2::PidfdExited,
                boot_id,
                boot_id,
                observed_at_seconds,
                process_id,
                start_time_ticks,
                process_instance,
                process_execution_digest,
            ),
            DeathEvidenceV1::CrossBoot {
                old_boot_id,
                current_boot_id,
                observed_at_seconds,
                process_id,
                start_time_ticks,
                process_instance,
                process_execution_digest,
            } => (
                ProviderExecutionDeathKindV2::BootReplaced,
                old_boot_id,
                current_boot_id,
                observed_at_seconds,
                process_id,
                start_time_ticks,
                process_instance,
                process_execution_digest,
            ),
        };
        let mut projection = DeadProviderExecutionProjectionV2 {
            kind,
            old_boot_id,
            observed_boot_id,
            observed_at_seconds,
            process_id,
            start_time_ticks,
            process_instance,
            process_execution_digest,
            commitment: ObjectDigest::from_bytes([0; 32]),
        };
        projection.commitment = death_projection_commitment(&projection);
        projection
    }

    pub(crate) fn establish_from_current_custody(
        old_boot_id: [u8; 16],
        old_process_id: u32,
        old_start_time_ticks: u64,
        process_instance: [u8; 16],
        process_execution_digest: ObjectDigest,
    ) -> Result<Self, SourceProviderSecurityError> {
        Self::observe_from_current_custody(
            old_boot_id,
            old_process_id,
            old_start_time_ticks,
            process_instance,
            process_execution_digest,
        )?
        .ok_or(SourceProviderSecurityError::DeathNotEstablished)
    }

    /// Returns `None` only for a pinned, exact live predecessor process.
    pub(crate) fn observe_from_current_custody(
        old_boot_id: [u8; 16],
        old_process_id: u32,
        old_start_time_ticks: u64,
        process_instance: [u8; 16],
        process_execution_digest: ObjectDigest,
    ) -> Result<Option<Self>, SourceProviderSecurityError> {
        let current = CurrentKernelBootV1::capture()?;
        if current.boot_id() != old_boot_id {
            return Self::cross_boot(
                &current,
                RecoveredProviderExecutionV1 {
                    old_boot_id,
                    process_id: old_process_id,
                    start_time_ticks: old_start_time_ticks,
                    process_instance,
                    process_execution_digest,
                },
            )
            .map(Some);
        }
        Self::observe_same_boot_recovered(
            &current,
            old_process_id,
            old_start_time_ticks,
            process_instance,
            process_execution_digest,
        )
    }

    /// Reports whether this proof names the exact recovered execution.
    #[must_use]
    pub fn matches(
        &self,
        boot_id: [u8; 16],
        process_id: u32,
        start_time_ticks: u64,
        process_instance: [u8; 16],
    ) -> bool {
        match self.evidence {
            DeathEvidenceV1::SameBoot {
                boot_id: proven_boot,
                process_id: proven_process_id,
                start_time_ticks: proven_start,
                process_instance: proven_process,
                ..
            } => {
                proven_boot == boot_id
                    && proven_process_id == process_id
                    && proven_start == start_time_ticks
                    && proven_process == process_instance
            }
            DeathEvidenceV1::CrossBoot {
                old_boot_id,
                process_id: proven_process_id,
                start_time_ticks: proven_start,
                process_instance: proven_process,
                ..
            } => {
                old_boot_id == boot_id
                    && proven_process_id == process_id
                    && proven_start == start_time_ticks
                    && proven_process == process_instance
            }
        }
    }

    pub(super) fn same_boot(
        execution: &ProcessExecutionEvidenceV1,
        _closed_carrier: ClosedSourceProviderCarrierV1,
        _unresolved: UnresolvedProviderSessionReceiptV1,
    ) -> Result<Self, SourceProviderSecurityError> {
        let boot_before = CurrentKernelBootV1::capture()?;
        if boot_before.boot_id() != execution.boot_id() || execution.is_alive()? {
            return Err(SourceProviderSecurityError::DeathNotEstablished);
        }
        let boot_after = CurrentKernelBootV1::capture()?;
        if boot_after.boot_id() != boot_before.boot_id() || execution.is_alive()? {
            return Err(SourceProviderSecurityError::DeathNotEstablished);
        }
        Ok(Self {
            evidence: DeathEvidenceV1::SameBoot {
                boot_id: execution.boot_id(),
                observed_at_seconds: crate::handshake::current_unix_seconds()?,
                process_id: execution.pid(),
                start_time_ticks: execution.start_time_ticks(),
                process_instance: _unresolved.process_instance,
                process_execution_digest: full_execution_digest(execution),
            },
        })
    }

    fn observe_same_boot_recovered(
        current: &CurrentKernelBootV1,
        old_process_id: u32,
        old_start_time_ticks: u64,
        process_instance: [u8; 16],
        process_execution_digest: ObjectDigest,
    ) -> Result<Option<Self>, SourceProviderSecurityError> {
        let process_id = NonZeroU32::new(old_process_id)
            .ok_or(SourceProviderSecurityError::DeathNotEstablished)?;
        current.revalidate()?;
        let death_established = match PidFd::open(process_id) {
            Ok(pidfd) => {
                let alive = pidfd
                    .is_alive()
                    .map_err(|_| SourceProviderSecurityError::DeathNotEstablished)?;
                if !alive {
                    true
                } else {
                    let identity = pidfd
                        .process_identity()
                        .map_err(|_| SourceProviderSecurityError::DeathNotEstablished)?;
                    if identity.pid() != old_process_id {
                        return Err(SourceProviderSecurityError::DeathNotEstablished);
                    }
                    identity.start_time_ticks() != old_start_time_ticks
                        || !pidfd
                            .is_alive()
                            .map_err(|_| SourceProviderSecurityError::DeathNotEstablished)?
                }
            }
            Err(aos_sandbox_linux::Error::Syscall { source, .. })
                if source.raw_os_error() == Some(libc::ESRCH) =>
            {
                true
            }
            Err(_) => return Err(SourceProviderSecurityError::DeathNotEstablished),
        };
        current.revalidate()?;
        if process_instance == [0; 16]
            || old_start_time_ticks == 0
            || process_execution_digest.as_bytes() == &[0; 32]
        {
            return Err(SourceProviderSecurityError::DeathNotEstablished);
        }
        if !death_established {
            return Ok(None);
        }
        Ok(Some(Self {
            evidence: DeathEvidenceV1::SameBoot {
                boot_id: current.boot_id(),
                observed_at_seconds: crate::handshake::current_unix_seconds()?,
                process_id: old_process_id,
                start_time_ticks: old_start_time_ticks,
                process_instance,
                process_execution_digest,
            },
        }))
    }

    pub(super) fn cross_boot(
        current: &CurrentKernelBootV1,
        recovered: RecoveredProviderExecutionV1,
    ) -> Result<Self, SourceProviderSecurityError> {
        current.revalidate()?;
        if current.boot_id() == recovered.old_boot_id
            || recovered.old_boot_id == [0; 16]
            || recovered.process_id == 0
            || recovered.start_time_ticks == 0
            || recovered.process_instance == [0; 16]
            || recovered.process_execution_digest.as_bytes() == &[0; 32]
        {
            return Err(SourceProviderSecurityError::DeathNotEstablished);
        }
        Ok(Self {
            evidence: DeathEvidenceV1::CrossBoot {
                old_boot_id: recovered.old_boot_id,
                current_boot_id: current.boot_id(),
                observed_at_seconds: crate::handshake::current_unix_seconds()?,
                process_id: recovered.process_id,
                start_time_ticks: recovered.start_time_ticks,
                process_instance: recovered.process_instance,
                process_execution_digest: recovered.process_execution_digest,
            },
        })
    }
}

fn death_projection_commitment(projection: &DeadProviderExecutionProjectionV2) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.source-provider.execution-death-projection.v2\0");
    hasher.update([match projection.kind {
        ProviderExecutionDeathKindV2::PidfdExited => 1,
        ProviderExecutionDeathKindV2::BootReplaced => 2,
    }]);
    hasher.update([0; 7]);
    hasher.update(projection.old_boot_id);
    hasher.update(projection.observed_boot_id);
    hasher.update(projection.observed_at_seconds.to_be_bytes());
    hasher.update(projection.process_id.to_be_bytes());
    hasher.update(projection.start_time_ticks.to_be_bytes());
    hasher.update(projection.process_instance);
    hasher.update(projection.process_execution_digest.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;
    use std::process::Command;
    use std::time::Duration;

    use aos_sandbox_core::ObjectDigest;
    use aos_sandbox_linux::pidfd::PidFd;

    use super::{CurrentKernelBootV1, DeadProviderExecutionV1, RecoveredProviderExecutionV1};

    #[test]
    fn death_proof_child_process() {
        if std::env::var_os("AOS_SOURCE_PROVIDER_DEATH_PROOF_CHILD").is_some() {
            std::thread::sleep(Duration::from_secs(10));
        }
    }

    #[test]
    fn recovered_death_requires_old_process_exit() {
        let executable = std::env::current_exe().expect("current test executable");
        let mut child = Command::new(executable)
            .arg("--exact")
            .arg("execution::death::tests::death_proof_child_process")
            .env("AOS_SOURCE_PROVIDER_DEATH_PROOF_CHILD", "1")
            .spawn()
            .expect("spawn test executable child");
        let process_id = NonZeroU32::new(child.id()).expect("child PID");
        let pidfd = PidFd::open(process_id).expect("pin child process");
        let identity = pidfd.process_identity().expect("observe child identity");
        let boot = CurrentKernelBootV1::capture().expect("capture kernel boot");
        let process_instance = [7; 16];
        let execution_digest = ObjectDigest::from_bytes([8; 32]);

        assert!(
            DeadProviderExecutionV1::observe_same_boot_recovered(
                &boot,
                process_id.get(),
                identity.start_time_ticks(),
                process_instance,
                execution_digest,
            )
            .expect("exact live observation")
            .is_none()
        );
        assert!(
            DeadProviderExecutionV1::observe_same_boot_recovered(
                &boot,
                0,
                identity.start_time_ticks(),
                process_instance,
                execution_digest,
            )
            .is_err(),
            "an unobservable predecessor is not a live-session witness"
        );

        child.kill().expect("stop child");
        child.wait().expect("reap child");
        let proof = DeadProviderExecutionV1::observe_same_boot_recovered(
            &boot,
            process_id.get(),
            identity.start_time_ticks(),
            process_instance,
            execution_digest,
        )
        .expect("observe exited exact process")
        .expect("prove exited exact process");
        assert!(proof.matches(
            boot.boot_id(),
            process_id.get(),
            identity.start_time_ticks(),
            process_instance,
        ));
    }

    #[test]
    fn cross_boot_death_rejects_unchanged_boot_identity() {
        let boot = CurrentKernelBootV1::capture().expect("capture kernel boot");
        let recovered = RecoveredProviderExecutionV1 {
            old_boot_id: boot.boot_id(),
            process_id: std::process::id(),
            start_time_ticks: 1,
            process_instance: [7; 16],
            process_execution_digest: ObjectDigest::from_bytes([8; 32]),
        };

        assert!(DeadProviderExecutionV1::cross_boot(&boot, recovered).is_err());
    }
}

fn full_execution_digest(execution: &ProcessExecutionEvidenceV1) -> ObjectDigest {
    let credentials = execution.credentials();
    let values = [
        credentials.real_user_id(),
        credentials.effective_user_id(),
        credentials.saved_user_id(),
        credentials.filesystem_user_id(),
        credentials.real_group_id(),
        credentials.effective_group_id(),
        credentials.saved_group_id(),
        credentials.filesystem_group_id(),
    ];
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.mount.source-provider-execution.v2\0");
    hasher.update(execution.pid().to_be_bytes());
    hasher.update(execution.tgid().to_be_bytes());
    hasher.update(execution.parent_pid().to_be_bytes());
    hasher.update(execution.start_time_ticks().to_be_bytes());
    hasher.update(execution.cgroup_id().to_be_bytes());
    for value in values {
        hasher.update(value.to_be_bytes());
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}
